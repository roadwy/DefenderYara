
rule Trojan_Win32_Iceid_BB_MTB{
	meta:
		description = "Trojan:Win32/Iceid.BB!MTB,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {6a 43 83 04 24 fd 68 03 10 00 00 83 04 24 fd 68 d3 08 00 00 83 04 24 fd 6a 00 } //1
		$a_01_1 = {41 4a 48 52 4b 49 54 2e 44 4c 4c } //1 AJHRKIT.DLL
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}