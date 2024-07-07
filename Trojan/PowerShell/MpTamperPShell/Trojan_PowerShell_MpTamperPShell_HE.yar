
rule Trojan_PowerShell_MpTamperPShell_HE{
	meta:
		description = "Trojan:PowerShell/MpTamperPShell.HE,SIGNATURE_TYPE_CMDHSTR_EXT,ffffff91 01 ffffff91 01 13 00 00 "
		
	strings :
		$a_00_0 = {73 00 65 00 74 00 2d 00 6d 00 70 00 70 00 72 00 65 00 66 00 65 00 72 00 65 00 6e 00 63 00 65 00 20 00 2d 00 66 00 6f 00 72 00 63 00 65 00 } //100 set-mppreference -force
		$a_00_1 = {69 00 66 00 28 00 21 00 24 00 63 00 6f 00 6d 00 6d 00 61 00 6e 00 64 00 2e 00 70 00 61 00 72 00 61 00 6d 00 65 00 74 00 65 00 72 00 73 00 2e 00 6b 00 65 00 79 00 73 00 2e 00 63 00 6f 00 6e 00 74 00 61 00 69 00 6e 00 73 00 28 00 24 00 70 00 72 00 6f 00 70 00 65 00 72 00 74 00 79 00 6e 00 61 00 6d 00 65 00 29 00 29 00 } //100 if(!$command.parameters.keys.contains($propertyname))
		$a_00_2 = {24 00 5f 00 2e 00 66 00 75 00 6c 00 6c 00 79 00 71 00 75 00 61 00 6c 00 69 00 66 00 69 00 65 00 64 00 65 00 72 00 72 00 6f 00 72 00 69 00 64 00 20 00 2d 00 6c 00 69 00 6b 00 65 00 20 00 27 00 2a 00 30 00 78 00 38 00 30 00 30 00 31 00 30 00 36 00 62 00 61 00 2a 00 27 00 } //100 $_.fullyqualifiederrorid -like '*0x800106ba*'
		$a_00_3 = {64 00 65 00 66 00 65 00 6e 00 64 00 65 00 72 00 20 00 73 00 65 00 72 00 76 00 69 00 63 00 65 00 20 00 28 00 77 00 69 00 6e 00 64 00 65 00 66 00 65 00 6e 00 64 00 29 00 20 00 69 00 73 00 20 00 6e 00 6f 00 74 00 20 00 72 00 75 00 6e 00 6e 00 69 00 6e 00 67 00 2e 00 20 00 74 00 72 00 79 00 20 00 74 00 6f 00 20 00 65 00 6e 00 61 00 62 00 6c 00 65 00 20 00 69 00 74 00 20 00 28 00 72 00 65 00 76 00 65 00 72 00 74 00 29 00 20 00 61 00 6e 00 64 00 20 00 72 00 65 00 2d 00 72 00 75 00 6e 00 20 00 74 00 68 00 69 00 73 00 3f 00 } //100 defender service (windefend) is not running. try to enable it (revert) and re-run this?
		$a_00_4 = {64 00 69 00 73 00 61 00 62 00 6c 00 65 00 69 00 6f 00 61 00 76 00 70 00 72 00 6f 00 74 00 65 00 63 00 74 00 69 00 6f 00 6e 00 } //1 disableioavprotection
		$a_00_5 = {64 00 69 00 73 00 61 00 62 00 6c 00 65 00 72 00 65 00 73 00 74 00 6f 00 72 00 65 00 70 00 6f 00 69 00 6e 00 74 00 } //1 disablerestorepoint
		$a_00_6 = {70 00 75 00 61 00 70 00 72 00 6f 00 74 00 65 00 63 00 74 00 69 00 6f 00 6e 00 } //1 puaprotection
		$a_00_7 = {64 00 69 00 73 00 61 00 62 00 6c 00 65 00 72 00 65 00 6d 00 6f 00 76 00 61 00 62 00 6c 00 65 00 64 00 72 00 69 00 76 00 65 00 73 00 63 00 61 00 6e 00 6e 00 69 00 6e 00 67 00 } //1 disableremovabledrivescanning
		$a_00_8 = {64 00 69 00 73 00 61 00 62 00 6c 00 65 00 63 00 61 00 74 00 63 00 68 00 75 00 70 00 71 00 75 00 69 00 63 00 6b 00 73 00 63 00 61 00 6e 00 } //1 disablecatchupquickscan
		$a_00_9 = {64 00 69 00 73 00 61 00 62 00 6c 00 65 00 62 00 6c 00 6f 00 63 00 6b 00 61 00 74 00 66 00 69 00 72 00 73 00 74 00 73 00 65 00 65 00 6e 00 } //1 disableblockatfirstseen
		$a_00_10 = {64 00 69 00 73 00 61 00 62 00 6c 00 65 00 61 00 75 00 74 00 6f 00 65 00 78 00 63 00 6c 00 75 00 73 00 69 00 6f 00 6e 00 73 00 } //1 disableautoexclusions
		$a_00_11 = {64 00 69 00 73 00 61 00 62 00 6c 00 65 00 70 00 72 00 69 00 76 00 61 00 63 00 79 00 6d 00 6f 00 64 00 65 00 } //1 disableprivacymode
		$a_00_12 = {64 00 69 00 73 00 61 00 62 00 6c 00 65 00 69 00 6e 00 74 00 72 00 75 00 73 00 69 00 6f 00 6e 00 70 00 72 00 65 00 76 00 65 00 6e 00 74 00 69 00 6f 00 6e 00 73 00 79 00 73 00 74 00 65 00 6d 00 } //1 disableintrusionpreventionsystem
		$a_00_13 = {64 00 69 00 73 00 61 00 62 00 6c 00 65 00 62 00 65 00 68 00 61 00 76 00 69 00 6f 00 72 00 6d 00 6f 00 6e 00 69 00 74 00 6f 00 72 00 69 00 6e 00 67 00 } //1 disablebehaviormonitoring
		$a_00_14 = {64 00 69 00 73 00 61 00 62 00 6c 00 65 00 72 00 65 00 61 00 6c 00 74 00 69 00 6d 00 65 00 6d 00 6f 00 6e 00 69 00 74 00 6f 00 72 00 69 00 6e 00 67 00 } //1 disablerealtimemonitoring
		$a_00_15 = {64 00 69 00 73 00 61 00 62 00 6c 00 65 00 73 00 63 00 72 00 69 00 70 00 74 00 73 00 63 00 61 00 6e 00 6e 00 69 00 6e 00 67 00 } //1 disablescriptscanning
		$a_00_16 = {64 00 69 00 73 00 61 00 62 00 6c 00 65 00 61 00 72 00 63 00 68 00 69 00 76 00 65 00 73 00 63 00 61 00 6e 00 6e 00 69 00 6e 00 67 00 } //1 disablearchivescanning
		$a_00_17 = {64 00 69 00 73 00 61 00 62 00 6c 00 65 00 65 00 6d 00 61 00 69 00 6c 00 73 00 63 00 61 00 6e 00 6e 00 69 00 6e 00 67 00 } //1 disableemailscanning
		$a_00_18 = {64 00 69 00 73 00 61 00 62 00 6c 00 65 00 73 00 63 00 61 00 6e 00 6e 00 69 00 6e 00 67 00 6d 00 61 00 70 00 70 00 65 00 64 00 6e 00 65 00 74 00 77 00 6f 00 72 00 6b 00 64 00 72 00 69 00 76 00 65 00 73 00 66 00 6f 00 72 00 66 00 75 00 6c 00 6c 00 73 00 63 00 61 00 6e 00 } //1 disablescanningmappednetworkdrivesforfullscan
	condition:
		((#a_00_0  & 1)*100+(#a_00_1  & 1)*100+(#a_00_2  & 1)*100+(#a_00_3  & 1)*100+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1+(#a_00_7  & 1)*1+(#a_00_8  & 1)*1+(#a_00_9  & 1)*1+(#a_00_10  & 1)*1+(#a_00_11  & 1)*1+(#a_00_12  & 1)*1+(#a_00_13  & 1)*1+(#a_00_14  & 1)*1+(#a_00_15  & 1)*1+(#a_00_16  & 1)*1+(#a_00_17  & 1)*1+(#a_00_18  & 1)*1) >=401
 
}