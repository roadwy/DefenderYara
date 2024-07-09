
rule Trojan_WinNT_Qsbot_A{
	meta:
		description = "Trojan:WinNT/Qsbot.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {0f b7 33 43 66 89 32 43 42 42 66 85 f6 75 f1 8b 47 14 89 41 48 33 c0 89 41 30 89 41 34 89 41 28 89 41 2c } //1
		$a_03_1 = {fa 0f 20 c0 25 ff ff fe ff 0f 22 c0 a1 ?? ?? ?? ?? c7 00 ?? ?? ?? ?? a1 ?? ?? ?? ?? c7 00 ?? ?? ?? ?? 0f 20 c0 0d 00 00 01 00 0f 22 c0 fb c6 02 01 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}