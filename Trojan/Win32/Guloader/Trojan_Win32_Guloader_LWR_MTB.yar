
rule Trojan_Win32_Guloader_LWR_MTB{
	meta:
		description = "Trojan:Win32/Guloader.LWR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_81_0 = {69 73 6f 74 72 69 6d 6f 72 70 68 69 63 2e 74 61 6d } //1 isotrimorphic.tam
		$a_81_1 = {6f 61 72 6c 6f 63 6b 2e 66 6f 64 } //1 oarlock.fod
		$a_81_2 = {64 69 67 74 73 61 6d 6c 69 6e 67 65 72 2e 6f 76 65 } //1 digtsamlinger.ove
		$a_81_3 = {72 6f 74 74 65 66 6c 64 65 2e 66 6c 61 } //1 rotteflde.fla
		$a_81_4 = {6d 6f 6e 61 72 63 68 69 63 20 6a 6f 6d 66 72 75 74 61 6c 65 72 20 74 6f 77 65 72 77 6f 72 74 } //1 monarchic jomfrutaler towerwort
		$a_81_5 = {63 6f 63 61 69 6e 69 73 65 64 20 62 6c 65 73 73 65 64 65 73 74 } //1 cocainised blessedest
		$a_81_6 = {63 68 61 72 6c 61 74 61 6e 65 72 69 65 72 73 } //1 charlataneriers
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1) >=7
 
}