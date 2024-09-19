
rule Trojan_Win32_RHADAMANTHYS_DA_MTB{
	meta:
		description = "Trojan:Win32/RHADAMANTHYS.DA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,47 00 47 00 0b 00 00 "
		
	strings :
		$a_81_0 = {4e 42 44 65 76 69 63 65 47 65 74 49 64 41 } //10 NBDeviceGetIdA
		$a_81_1 = {4e 42 44 65 76 69 63 65 47 65 74 53 74 61 74 65 } //10 NBDeviceGetState
		$a_81_2 = {4e 42 44 65 76 69 63 65 53 75 70 70 6f 72 74 73 4e 42 55 41 70 69 } //10 NBDeviceSupportsNBUApi
		$a_81_3 = {4e 42 45 72 72 6f 72 73 47 65 74 4d 65 73 73 61 67 65 41 } //10 NBErrorsGetMessageA
		$a_81_4 = {4e 42 45 72 72 6f 72 73 53 65 74 4c 61 73 74 41 } //10 NBErrorsSetLastA
		$a_81_5 = {4e 42 55 41 62 6f 72 74 } //10 NBUAbort
		$a_81_6 = {4e 42 55 69 64 61 69 2e 64 6c 6c } //10 NBUidai.dll
		$a_81_7 = {41 6c 70 68 61 42 6c 65 6e 64 } //1 AlphaBlend
		$a_81_8 = {54 72 61 6e 73 70 61 72 65 6e 74 42 } //1 TransparentB
		$a_81_9 = {43 72 65 61 74 65 46 6f 6e 74 50 61 63 6b 61 } //1 CreateFontPacka
		$a_81_10 = {47 72 61 64 69 65 6e 74 46 69 6c 6c } //1 GradientFill
	condition:
		((#a_81_0  & 1)*10+(#a_81_1  & 1)*10+(#a_81_2  & 1)*10+(#a_81_3  & 1)*10+(#a_81_4  & 1)*10+(#a_81_5  & 1)*10+(#a_81_6  & 1)*10+(#a_81_7  & 1)*1+(#a_81_8  & 1)*1+(#a_81_9  & 1)*1+(#a_81_10  & 1)*1) >=71
 
}