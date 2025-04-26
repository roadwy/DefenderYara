
rule Backdoor_Win32_PcClient_CW{
	meta:
		description = "Backdoor:Win32/PcClient.CW,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_00_0 = {53 65 72 76 69 63 65 4d 61 69 6e 00 } //1 敓癲捩䵥楡n
		$a_00_1 = {53 65 6e 73 4e 6f 74 69 66 79 4e 65 74 63 6f 6e 45 76 65 6e 74 00 } //1 敓獮潎楴祦敎捴湯癅湥t
		$a_00_2 = {53 65 6e 73 4e 6f 74 69 66 79 52 61 73 45 76 65 6e 74 00 } //1
		$a_00_3 = {53 65 6e 73 4e 6f 74 69 66 79 57 69 6e 6c 6f 67 6f 6e 45 76 65 6e 74 00 } //1 敓獮潎楴祦楗汮杯湯癅湥t
		$a_02_4 = {ff ff 68 c6 85 ?? ?? ff ff 74 c6 85 ?? ?? ff ff 74 c6 85 ?? ?? ff ff 70 c6 85 ?? ?? ff ff 3a c6 85 ?? ?? ff ff 2f c6 85 ?? ?? ff ff 2f c6 85 ?? ?? ff ff 25 c6 85 ?? ?? ff ff 73 c6 85 ?? ?? ff ff 3a c6 85 ?? ?? ff ff 25 c6 85 ?? ?? ff ff 64 c6 85 ?? ?? ff ff 2f c6 85 ?? ?? ff ff 25 c6 85 ?? ?? ff ff 73 c6 85 ?? ?? ff ff 25 c6 85 ?? ?? ff ff 64 c6 85 ?? ?? ff ff 25 c6 85 ?? ?? ff ff 30 c6 85 ?? ?? ff ff 38 c6 85 ?? ?? ff ff 64 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_02_4  & 1)*1) >=5
 
}