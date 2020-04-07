void printbinchar(char character)
{
	int i;
    for (i = 0; i < 8; i++) {
      printf("%d", !!((character << i) & 0x80));
  }
  printf("\n");
}

void printPayload(int len, char* payload)
{
	int i;

	for (i = 0; i < len; i++)
	{
		printbinchar(payload[i]);
	}
}
