
rule Trojan_Win64_ValleyRat_AD_MTB{
	meta:
		description = "Trojan:Win64/ValleyRat.AD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_81_0 = {73 63 68 74 61 73 6b 73 62 69 6e 50 61 74 68 3d 50 72 6f 67 72 61 6d 73 2f 2f 6e 6f 6c 6f 67 6f 47 6f 53 74 72 69 6e 67 75 6e 6c 69 6e 6b 61 74 6f 70 65 6e 66 64 61 74 46 75 6c 6c 50 61 74 68 6e } //1 schtasksbinPath=Programs//nologoGoStringunlinkatopenfdatFullPathn
		$a_81_1 = {6d 61 69 6e 2e 73 65 74 75 70 41 75 74 6f 53 74 61 72 74 } //1 main.setupAutoStart
		$a_81_2 = {6d 61 69 6e 2e 73 65 74 48 69 64 64 65 6e } //1 main.setHidden
		$a_81_3 = {6d 61 69 6e 2e 61 64 64 53 63 68 65 64 75 6c 65 64 54 61 73 6b } //1 main.addScheduledTask
		$a_81_4 = {6d 61 69 6e 2e 61 64 64 52 75 6e 4f 6e 63 65 } //1 main.addRunOnce
		$a_81_5 = {6d 61 69 6e 2e 61 64 64 57 69 6e 6c 6f 67 6f 6e } //1 main.addWinlogon
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1) >=6
 
}