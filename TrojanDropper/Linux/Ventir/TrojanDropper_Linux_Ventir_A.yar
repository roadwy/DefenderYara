
rule TrojanDropper_Linux_Ventir_A{
	meta:
		description = "TrojanDropper:Linux/Ventir.A,SIGNATURE_TYPE_MACHOHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {3c 73 74 72 69 6e 67 3e 63 6f 6d 2e 75 70 64 61 74 65 64 2e 6c 61 75 6e 63 68 61 67 65 6e 74 3c 2f 73 74 72 69 6e 67 3e } //1 <string>com.updated.launchagent</string>
		$a_01_1 = {6c 6f 61 64 20 25 73 2f 63 6f 6d 2e 75 70 64 61 74 65 64 2e 6c 61 75 6e 63 68 61 67 65 6e 74 2e 70 6c 69 73 74 } //1 load %s/com.updated.launchagent.plist
		$a_01_2 = {74 61 72 20 2d 78 66 20 25 73 2f 6b 65 78 74 2e 74 61 72 } //1 tar -xf %s/kext.tar
		$a_01_3 = {2f 62 69 6e 2f 63 68 6d 6f 64 20 2d 52 20 37 35 35 20 2f 53 79 73 74 65 6d 2f 4c 69 62 72 61 72 79 2f 45 78 74 65 6e 73 69 6f 6e 73 2f 75 70 64 61 74 65 64 2e 6b 65 78 74 } //1 /bin/chmod -R 755 /System/Library/Extensions/updated.kext
		$a_03_4 = {2f 70 72 6f 63 2f 73 65 6c 66 2f 65 78 65 [0-10] 5b 25 73 5d [0-10] 25 73 2f 75 70 64 61 74 65 64 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_03_4  & 1)*1) >=5
 
}