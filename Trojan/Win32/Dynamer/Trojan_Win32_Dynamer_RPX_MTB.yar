
rule Trojan_Win32_Dynamer_RPX_MTB{
	meta:
		description = "Trojan:Win32/Dynamer.RPX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {c6 05 53 00 44 00 6c c6 05 4d 00 44 00 6c c6 05 4b 00 44 00 6e c6 05 51 00 44 00 64 c6 05 52 00 44 00 6c c6 05 49 00 44 00 65 c6 05 50 00 44 00 2e c6 05 4f 00 44 00 32 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}