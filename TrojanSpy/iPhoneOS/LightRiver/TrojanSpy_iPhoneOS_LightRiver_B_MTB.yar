
rule TrojanSpy_iPhoneOS_LightRiver_B_MTB{
	meta:
		description = "TrojanSpy:iPhoneOS/LightRiver.B!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,03 00 03 00 06 00 00 "
		
	strings :
		$a_00_0 = {6c 6f 61 64 4c 69 67 68 74 } //1 loadLight
		$a_00_1 = {2f 76 61 72 2f 69 6f 6c 69 67 68 74 } //1 /var/iolight
		$a_00_2 = {2f 62 69 6e 2f 69 72 63 5f 6c 6f 61 64 65 72 } //1 /bin/irc_loader
		$a_00_3 = {63 6f 6d 2e 6d 79 61 70 70 2e 75 64 69 64 2e 6c 69 67 68 74 } //1 com.myapp.udid.light
		$a_00_4 = {73 65 6e 64 43 6f 6d 6d 6e 61 64 4f 76 65 72 } //1 sendCommnadOver
		$a_03_5 = {3c 6b 65 79 3e 6b 65 79 63 68 61 69 6e 2d 61 63 63 65 73 73 2d 67 72 6f 75 70 73 3c 2f 6b 65 79 3e 90 05 15 04 09 20 0a 0d 3c 61 72 72 61 79 3e 90 05 15 04 09 20 0a 0d 3c 73 74 72 69 6e 67 3e 2a 3c 2f 73 74 72 69 6e 67 3e 90 05 15 04 09 20 0a 0d 3c 2f 61 72 72 61 79 3e } //1
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_03_5  & 1)*1) >=3
 
}