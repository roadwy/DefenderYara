
rule Backdoor_Win64_TinyTurla_RHA_MTB{
	meta:
		description = "Backdoor:Win64/TinyTurla.RHA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 09 00 00 "
		
	strings :
		$a_00_0 = {54 00 69 00 74 00 6c 00 65 00 3a 00 } //1 Title:
		$a_00_1 = {48 00 6f 00 73 00 74 00 73 00 } //1 Hosts
		$a_00_2 = {53 00 65 00 63 00 75 00 72 00 69 00 74 00 79 00 } //1 Security
		$a_00_3 = {54 00 69 00 6d 00 65 00 4c 00 6f 00 6e 00 67 00 } //1 TimeLong
		$a_00_4 = {4d 00 61 00 63 00 68 00 69 00 6e 00 65 00 47 00 75 00 69 00 64 00 } //1 MachineGuid
		$a_01_5 = {57 69 6e 48 74 74 70 53 65 74 4f 70 74 69 6f 6e } //1 WinHttpSetOption
		$a_01_6 = {2e 64 6c 6c 00 53 65 72 76 69 63 65 4d 61 69 6e } //1 搮汬匀牥楶散慍湩
		$a_02_7 = {4f 00 72 00 69 00 67 00 69 00 6e 00 61 00 6c 00 46 00 69 00 6c 00 65 00 6e 00 61 00 6d 00 65 00 ?? ?? 77 00 36 00 34 00 74 00 69 00 6d 00 65 00 2e 00 64 00 6c 00 6c 00 } //1
		$a_03_8 = {50 45 00 00 64 86 05 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 0b 02 0e 0c 00 1e 00 00 00 12 00 00 00 00 00 00 50 24 } //2
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_02_7  & 1)*1+(#a_03_8  & 1)*2) >=10
 
}