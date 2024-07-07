
rule Trojan_MacOS_Infostealer_A{
	meta:
		description = "Trojan:MacOS/Infostealer.A,SIGNATURE_TYPE_MACHOHSTR_EXT,07 00 07 00 08 00 00 "
		
	strings :
		$a_00_0 = {73 79 73 74 65 6d 5f 70 72 6f 66 69 6c 65 72 20 53 50 48 61 72 64 77 61 72 65 44 61 74 61 54 79 70 65 20 3e } //1 system_profiler SPHardwareDataType >
		$a_00_1 = {2f 4c 69 62 72 61 72 79 2f 41 70 70 6c 69 63 61 74 69 6f 6e 20 53 75 70 70 6f 72 74 2f 7a 6f 6f 6d 2e 75 73 2f 64 61 74 61 2f 7a 6f 6f 6d 75 73 2e 65 6e 63 2e 64 62 } //1 /Library/Application Support/zoom.us/data/zoomus.enc.db
		$a_00_2 = {2f 44 65 73 6b 74 6f 70 20 2d 6d 61 78 64 65 70 74 68 20 31 20 2d 6e 61 6d 65 20 22 2a 2e 74 78 74 22 20 3e } //1 /Desktop -maxdepth 1 -name "*.txt" >
		$a_00_3 = {2f 44 6f 63 75 6d 65 6e 74 73 20 2d 6d 61 78 64 65 70 74 68 20 31 20 2d 6e 61 6d 65 20 22 2a 2e 74 78 74 22 20 3e } //1 /Documents -maxdepth 1 -name "*.txt" >
		$a_00_4 = {2f 64 65 76 2f 6e 75 6c 6c 20 66 69 6e 64 2d 67 65 6e 65 72 69 63 2d 70 61 73 73 77 6f 72 64 20 2d 67 61 20 27 43 68 72 6f 6d 65 27 } //1 /dev/null find-generic-password -ga 'Chrome'
		$a_00_5 = {61 77 6b 20 27 7b 70 72 69 6e 74 20 24 32 7d 27 20 3e } //1 awk '{print $2}' >
		$a_00_6 = {2e 74 78 74 20 26 26 20 72 6d 20 2d 52 66 } //1 .txt && rm -Rf
		$a_00_7 = {75 73 65 72 62 6f 74 3d } //1 userbot=
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1+(#a_00_7  & 1)*1) >=7
 
}