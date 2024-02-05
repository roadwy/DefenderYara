
rule Trojan_Win32_Gepys_DSK_MTB{
	meta:
		description = "Trojan:Win32/Gepys.DSK!MTB,SIGNATURE_TYPE_PEHSTR,05 00 05 00 03 00 00 02 00 "
		
	strings :
		$a_01_0 = {88 d9 a3 84 dd 42 00 a1 88 dd 42 00 d3 e8 05 55 75 04 00 8a 0d 84 dd 42 00 a3 88 dd 42 00 89 d8 d3 e0 03 05 84 dd 42 00 eb } //02 00 
		$a_01_1 = {51 88 df 8a 08 fe cf 20 f9 8a 3a 00 df 08 d9 88 38 88 0a 59 } //01 00 
		$a_01_2 = {4c 00 65 00 48 00 7a 00 44 00 44 00 67 00 43 00 75 00 6c 00 51 00 42 00 7a 00 73 00 73 00 52 00 71 00 } //00 00 
	condition:
		any of ($a_*)
 
}