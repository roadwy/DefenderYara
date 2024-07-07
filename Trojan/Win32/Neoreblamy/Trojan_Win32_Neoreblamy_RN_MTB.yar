
rule Trojan_Win32_Neoreblamy_RN_MTB{
	meta:
		description = "Trojan:Win32/Neoreblamy.RN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {51 51 68 cf 00 00 00 68 24 32 00 00 51 52 51 51 68 ec 48 00 00 ff 75 0c 8d 55 fc b9 e7 1c 00 00 ff 75 08 e8 0a 00 00 00 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}