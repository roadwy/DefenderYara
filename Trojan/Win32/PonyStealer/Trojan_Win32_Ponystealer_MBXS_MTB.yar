
rule Trojan_Win32_Ponystealer_MBXS_MTB{
	meta:
		description = "Trojan:Win32/Ponystealer.MBXS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {11 51 00 18 f9 37 01 20 ff ff ff 08 00 00 00 01 00 00 00 02 00 00 00 e9 00 00 00 60 10 51 00 d4 0e 51 00 e0 11 40 00 78 00 00 00 83 00 00 00 8d 00 00 00 8e } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}