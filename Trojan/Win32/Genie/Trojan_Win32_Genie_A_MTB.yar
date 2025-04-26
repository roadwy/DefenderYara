
rule Trojan_Win32_Genie_A_MTB{
	meta:
		description = "Trojan:Win32/Genie.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {b8 74 66 48 00 50 64 ff 35 00 00 00 00 64 89 25 00 00 00 00 33 c0 89 08 50 45 43 6f 6d 70 61 63 74 32 00 7a b3 7d f7 64 ae } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}