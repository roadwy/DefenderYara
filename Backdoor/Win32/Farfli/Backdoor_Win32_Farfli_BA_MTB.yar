
rule Backdoor_Win32_Farfli_BA_MTB{
	meta:
		description = "Backdoor:Win32/Farfli.BA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,10 00 10 00 04 00 00 "
		
	strings :
		$a_02_0 = {8a 04 39 bd ?? ?? ?? ?? 80 c2 1f 32 c2 46 88 04 39 8b c1 } //5
		$a_02_1 = {c6 44 24 1a 46 c6 44 24 1b ?? c6 44 24 1c ?? c6 44 24 1d ?? c6 44 24 1e ?? c6 44 24 1f ?? c6 44 24 20 ?? c6 44 24 22 44 c6 ?? 24 23 ?? c6 44 24 } //5
		$a_02_2 = {b0 6c b1 65 88 44 24 ?? 88 44 24 ?? 8d 44 24 ?? c6 44 24 ?? 53 50 c6 44 24 ?? 68 88 4c 24 ?? 88 4c 24 ?? c6 44 24 ?? 78 c6 44 24 0b 00 } //5
		$a_01_3 = {56 69 72 74 75 61 6c 50 72 6f 74 65 63 74 } //1 VirtualProtect
	condition:
		((#a_02_0  & 1)*5+(#a_02_1  & 1)*5+(#a_02_2  & 1)*5+(#a_01_3  & 1)*1) >=16
 
}