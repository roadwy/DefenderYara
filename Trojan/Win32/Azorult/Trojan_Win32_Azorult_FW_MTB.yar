
rule Trojan_Win32_Azorult_FW_MTB{
	meta:
		description = "Trojan:Win32/Azorult.FW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {e8 01 00 00 00 c3 55 8b ec 8d 45 c4 83 ec 3c 50 e8 0d 00 00 00 8d 45 c4 50 e8 88 07 00 00 59 59 c9 c3 55 8b ec 83 ec 38 53 56 57 8b 45 08 c6 00 00 83 65 fc 00 e8 00 00 00 00 58 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}