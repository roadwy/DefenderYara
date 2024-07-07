
rule Trojan_Win32_Fursto_C_dll{
	meta:
		description = "Trojan:Win32/Fursto.C!dll,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {39 75 fc 75 32 ff 75 0c e8 90 01 02 00 00 84 c0 59 74 25 be 90 01 02 00 10 56 ff 15 90 01 02 00 10 50 8b 45 0c 05 90 01 01 05 00 00 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}