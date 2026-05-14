
rule Trojan_Win32_Meterpreter_SX_MTB{
	meta:
		description = "Trojan:Win32/Meterpreter.SX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1e 00 1e 00 02 00 00 "
		
	strings :
		$a_03_0 = {8d 04 b3 8b d3 89 45 ?? 83 c4 0c 89 55 ?? 2b c2 c7 45 ?? 00 00 00 00 6a 40 8b f0 89 45 ?? 68 00 30 00 00 c1 fe 02 83 ec 0c } //20
		$a_03_1 = {f3 a5 8d 95 ?? ?? ?? ?? 0f 57 c0 8d 4d ?? 66 0f d6 45 ?? 2b ca 33 db 8b f1 89 5d ?? 33 c0 c1 fe 02 33 ff } //10
	condition:
		((#a_03_0  & 1)*20+(#a_03_1  & 1)*10) >=30
 
}