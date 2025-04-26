
rule Backdoor_Win32_Seenabhi_A{
	meta:
		description = "Backdoor:Win32/Seenabhi.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 05 00 00 "
		
	strings :
		$a_03_0 = {a5 a5 66 a5 66 a3 ?? ?? ?? ?? 8d 45 ?? 50 68 ?? ?? ?? ?? a4 c6 45 ?? 53 c6 45 ?? 65 c6 45 ?? 45 c6 45 ?? 6e } //2
		$a_03_1 = {8b 78 04 83 ff 2a 74 ?? 83 ff 71 74 ?? 81 ff 9a 02 00 00 75 } //1
		$a_01_2 = {30 65 74 33 74 64 36 61 6e 39 6c 65 } //1 0et3td6an9le
		$a_01_3 = {30 61 6b 33 72 35 76 65 38 74 } //1 0ak3r5ve8t
		$a_01_4 = {4a 75 73 74 54 65 6d 70 46 75 6e } //1 JustTempFun
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=3
 
}