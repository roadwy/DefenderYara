
rule Ransom_Win32_Ryuk_DHA_MTB{
	meta:
		description = "Ransom:Win32/Ryuk.DHA!MTB,SIGNATURE_TYPE_PEHSTR,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b c1 99 f7 7d 0c 8a 04 97 28 04 31 41 3b 4d 14 7c ee } //10
	condition:
		((#a_01_0  & 1)*10) >=10
 
}