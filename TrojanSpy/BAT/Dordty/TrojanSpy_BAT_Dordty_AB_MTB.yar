
rule TrojanSpy_BAT_Dordty_AB_MTB{
	meta:
		description = "TrojanSpy:BAT/Dordty.AB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_00_0 = {5c 00 64 00 69 00 73 00 63 00 6f 00 72 00 64 00 5c 00 4c 00 6f 00 63 00 61 00 6c 00 20 00 53 00 74 00 6f 00 72 00 61 00 67 00 65 00 5c 00 6c 00 65 00 76 00 65 00 6c 00 64 00 62 00 5c 00 } //1 \discord\Local Storage\leveldb\
		$a_02_1 = {44 69 73 63 6f 72 64 2d 54 6f 6b 65 6e 2d 47 72 61 62 62 65 72 2d 6d 61 73 74 65 72 [0-20] 44 69 73 63 6f 72 64 54 6f 6b 65 6e 47 72 61 62 62 65 72 } //1
		$a_00_2 = {54 00 6f 00 6b 00 65 00 6e 00 2e 00 74 00 78 00 74 00 } //1 Token.txt
		$a_00_3 = {54 00 6f 00 6b 00 65 00 6e 00 3d 00 } //1 Token=
		$a_00_4 = {53 65 61 72 63 68 46 6f 72 46 69 6c 65 } //1 SearchForFile
		$a_00_5 = {44 69 73 63 6f 72 64 54 6f 6b 65 6e 47 72 61 62 62 65 72 2e 65 78 65 } //1 DiscordTokenGrabber.exe
	condition:
		((#a_00_0  & 1)*1+(#a_02_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1) >=6
 
}