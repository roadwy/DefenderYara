
rule Trojan_Win32_Farfli_EGZV_MTB{
	meta:
		description = "Trojan:Win32/Farfli.EGZV!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {66 83 fe 02 75 02 33 f6 8a 14 39 0f b7 c6 80 ea 7a 8a 44 45 fc 32 c2 46 88 04 39 41 3b 4d 0c } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}