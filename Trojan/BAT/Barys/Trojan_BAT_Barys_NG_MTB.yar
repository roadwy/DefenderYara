
rule Trojan_BAT_Barys_NG_MTB{
	meta:
		description = "Trojan:BAT/Barys.NG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 05 00 00 "
		
	strings :
		$a_03_0 = {0b 06 07 03 61 d1 ?? ?? 00 00 0a 26 09 17 58 0d 09 08 } //2
		$a_01_1 = {0a 06 18 5d 2d 06 06 18 5d 17 2e 0a 06 19 } //1
		$a_81_2 = {2a 4b 2a 45 2a 52 2a 4e 2a 45 2a 4c 2a 33 2a 32 2a 2e 2a 44 2a 4c 2a 4c 2a } //1 *K*E*R*N*E*L*3*2*.*D*L*L*
		$a_81_3 = {44 65 62 75 67 67 65 72 2e 49 73 41 74 74 61 63 68 65 64 20 7c 7c 20 49 73 44 65 62 75 67 67 65 72 50 72 65 73 65 6e 74 28 29 } //1 Debugger.IsAttached || IsDebuggerPresent()
		$a_81_4 = {44 79 6e 61 6d 69 63 41 6e 74 69 44 65 62 75 67 } //1 DynamicAntiDebug
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1) >=6
 
}