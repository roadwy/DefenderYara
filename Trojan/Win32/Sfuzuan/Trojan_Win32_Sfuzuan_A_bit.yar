
rule Trojan_Win32_Sfuzuan_A_bit{
	meta:
		description = "Trojan:Win32/Sfuzuan.A!bit,SIGNATURE_TYPE_PEHSTR_EXT,20 00 20 00 07 00 00 "
		
	strings :
		$a_01_0 = {00 37 62 63 36 39 66 63 33 39 37 62 33 64 34 39 64 31 39 66 30 33 62 32 64 30 38 37 64 66 63 63 61 00 } //10 㜀换㤶捦㤳户搳㤴ㅤ昹㌰㉢つ㜸晤捣a
		$a_01_1 = {00 66 65 66 36 36 39 32 63 66 35 37 62 33 35 36 31 33 33 66 38 35 31 35 30 61 33 32 34 65 38 39 34 00 } //10 昀晥㘶㈹晣㜵㍢㘵㌱昳㔸㔱愰㈳攴㤸4
		$a_01_2 = {00 32 35 39 30 35 35 33 62 37 36 35 39 31 31 66 36 36 31 30 62 36 33 63 33 36 33 30 62 36 65 61 63 00 } //10 ㈀㤵㔰㌵㝢㔶ㄹ昱㘶〱㙢挳㘳〳㙢慥c
		$a_01_3 = {00 30 62 64 61 30 31 30 38 61 37 62 33 65 33 63 35 66 39 31 36 63 32 31 33 65 65 35 31 36 65 61 61 62 30 33 39 61 61 65 37 62 63 38 35 33 35 64 62 33 63 37 37 32 33 65 35 33 65 63 36 35 61 61 65 00 } //10
		$a_01_4 = {6c 00 6f 00 67 00 2e 00 64 00 61 00 74 00 00 00 43 00 6f 00 64 00 65 00 } //1
		$a_01_5 = {43 72 65 61 74 65 4d 75 74 65 78 57 00 00 00 00 32 00 33 00 34 00 64 00 66 00 35 00 66 00 67 00 33 00 34 00 00 } //1
		$a_03_6 = {8d 7c 24 3c f3 a5 68 a7 00 00 00 8d 4c ?? ?? 6a 00 51 89 44 ?? ?? a4 e8 ?? ?? 00 00 83 c4 0c 8d 54 24 3c 52 68 ?? ?? ?? ?? 8b c2 50 e8 ?? ?? 00 00 } //1
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10+(#a_01_2  & 1)*10+(#a_01_3  & 1)*10+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_03_6  & 1)*1) >=32
 
}