
rule Trojan_MacOS_GlassWorm_B_MTB{
	meta:
		description = "Trojan:MacOS/GlassWorm.B!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,05 00 05 00 06 00 00 "
		
	strings :
		$a_01_0 = {64 72 6f 70 70 65 72 5f 62 61 6e 4c 69 62 72 61 72 79 } //1 dropper_banLibrary
		$a_01_1 = {63 6f 6d 2e 61 70 70 6c 65 2e 75 70 64 65 76 65 6e 74 73 6c 61 75 6e 63 68 63 74 6c 72 65 6d 6f 76 65 } //1 com.apple.updeventslaunchctlremove
		$a_01_2 = {78 61 74 74 72 20 2d 63 20 20 26 26 20 63 68 6d 6f 64 20 37 37 37 20 73 68 2d 63 63 6f 6d 2e 61 70 70 6c 65 2e 64 6f 63 6b 73 74 6f 72 61 67 65 } //1 xattr -c  && chmod 777 sh-ccom.apple.dockstorage
		$a_01_3 = {52 75 6e 50 61 79 6c 6f 61 64 69 6e 70 75 74 62 69 6e 50 61 79 6c 6f 61 64 4f 75 74 70 75 74 6f 6b 6f 75 74 70 75 74 6c 6f 61 64 65 72 5f 72 75 6e 6e 69 6e 67 } //1 RunPayloadinputbinPayloadOutputokoutputloader_running
		$a_01_4 = {53 74 6f 72 61 67 65 73 65 72 76 65 72 5f 75 72 6c 73 65 72 76 65 72 5f 72 65 63 6f 76 65 72 79 } //1 Storageserver_urlserver_recovery
		$a_01_5 = {50 61 79 6c 6f 61 64 4f 75 74 70 75 74 6f 6b 6c 6f 61 64 65 72 5f 72 75 6e 6e 69 6e 67 } //1 PayloadOutputokloader_running
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=5
 
}