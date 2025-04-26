
rule Ransom_Win32_GandCrab_CC_MTB{
	meta:
		description = "Ransom:Win32/GandCrab.CC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 55 08 8b 12 8d 3c 02 8a 47 03 8a d0 8a d8 24 f0 02 c0 80 e2 fc 02 c0 0a 07 c0 e2 04 0a 57 01 c0 e3 06 0a 5f 02 88 04 31 8b 45 fc 41 88 14 31 8b 55 0c 41 88 1c 31 83 c0 04 41 89 7d 10 89 45 fc 3b 02 72 bb } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}