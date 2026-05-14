
rule Trojan_MacOS_SuspSupplyRAT_A{
	meta:
		description = "Trojan:MacOS/SuspSupplyRAT.A,SIGNATURE_TYPE_MACHOHSTR_EXT,0c 00 0c 00 0b 00 00 "
		
	strings :
		$a_00_0 = {76 61 72 2f 64 62 2f 2e 41 70 70 6c 65 53 65 74 75 70 44 6f 6e 65 } //2 var/db/.AppleSetupDone
		$a_00_1 = {6d 61 63 68 64 65 70 2e 63 70 75 2e 62 72 61 6e 64 5f 73 74 72 69 6e 67 } //1 machdep.cpu.brand_string
		$a_00_2 = {2f 70 72 69 76 61 74 65 2f 74 6d 70 2f 2e 25 73 } //1 /private/tmp/.%s
		$a_00_3 = {63 6f 64 65 73 69 67 6e 20 2d 2d 66 6f 72 63 65 20 2d 2d 64 65 65 70 20 2d 2d 73 69 67 6e } //1 codesign --force --deep --sign
		$a_00_4 = {2f 75 73 72 2f 62 69 6e 2f 6f 73 61 73 63 72 69 70 74 } //1 /usr/bin/osascript
		$a_00_5 = {72 73 70 5f 6b 69 6c 6c } //1 rsp_kill
		$a_00_6 = {70 65 69 6e 6a 65 63 74 } //1 peinject
		$a_00_7 = {72 73 70 5f 70 65 69 6e 6a 65 63 74 } //1 rsp_peinject
		$a_00_8 = {72 75 6e 73 63 72 69 70 74 } //1 runscript
		$a_00_9 = {72 73 70 5f 72 75 6e 73 63 72 69 70 74 } //1 rsp_runscript
		$a_00_10 = {72 73 70 5f 72 75 6e 64 69 72 } //1 rsp_rundir
	condition:
		((#a_00_0  & 1)*2+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1+(#a_00_7  & 1)*1+(#a_00_8  & 1)*1+(#a_00_9  & 1)*1+(#a_00_10  & 1)*1) >=12
 
}