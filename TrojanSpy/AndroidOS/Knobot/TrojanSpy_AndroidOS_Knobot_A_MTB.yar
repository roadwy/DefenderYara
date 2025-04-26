
rule TrojanSpy_AndroidOS_Knobot_A_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/Knobot.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 05 00 00 "
		
	strings :
		$a_00_0 = {63 65 61 6c 65 67 61 63 79 2e 6f 6e 6c 69 6e 65 } //1 cealegacy.online
		$a_00_1 = {62 6f 74 56 65 72 73 69 6f 6e } //1 botVersion
		$a_00_2 = {62 6f 74 6e 65 74 49 44 } //1 botnetID
		$a_00_3 = {77 70 70 69 65 6a 70 6d 6b 69 6a 6e 71 20 3d 20 22 65 76 65 6e 74 42 6f 74 22 } //1 wppiejpmkijnq = "eventBot"
		$a_00_4 = {46 61 69 6c 65 64 20 74 6f 20 67 65 74 20 6c 61 73 74 20 6b 6e 6f 77 6e 20 6c 6f 63 61 74 69 6f 6e } //1 Failed to get last known location
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=4
 
}