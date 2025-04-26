
rule TrojanSpy_AndroidOS_Krbot_A_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/Krbot.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 06 00 00 "
		
	strings :
		$a_01_0 = {63 6f 6d 2e 65 78 61 6d 70 6c 65 2e 64 61 74 2e 61 38 61 6e 64 6f 73 65 72 76 65 72 78 } //1 com.example.dat.a8andoserverx
		$a_00_1 = {2f 44 43 49 4d 2f 2e 66 64 61 74 } //1 /DCIM/.fdat
		$a_00_2 = {2f 44 43 49 4d 2f 2e 63 73 70 } //1 /DCIM/.csp
		$a_00_3 = {4d 79 57 61 6b 65 6c 6f 63 6b 54 67 67 67 61 67 } //1 MyWakelockTgggag
		$a_00_4 = {2f 44 43 49 4d 2f 2e 64 61 74 2f 4f 75 74 5f } //1 /DCIM/.dat/Out_
		$a_00_5 = {66 69 6c 65 3a 2f 2f 2f 73 64 63 61 72 64 2f 2e 61 70 70 2e 61 70 6b } //1 file:///sdcard/.app.apk
	condition:
		((#a_01_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1) >=5
 
}