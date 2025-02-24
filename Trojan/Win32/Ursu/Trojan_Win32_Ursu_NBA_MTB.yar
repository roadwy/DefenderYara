
rule Trojan_Win32_Ursu_NBA_MTB{
	meta:
		description = "Trojan:Win32/Ursu.NBA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,10 00 10 00 0f 00 00 "
		
	strings :
		$a_81_0 = {76 73 68 63 73 6f 2e 74 78 65 20 65 6b 2d 6e 20 74 65 76 73 73 63 } //2 vshcso.txe ek-n tevssc
		$a_81_1 = {53 65 72 76 69 63 65 2d 30 78 30 2d 33 65 37 24 5c 64 65 66 61 75 6c 74 } //1 Service-0x0-3e7$\default
		$a_81_2 = {65 6b 6e 72 6c 65 32 33 } //1 eknrle23
		$a_81_3 = {64 61 61 76 69 70 32 33 } //1 daavip23
		$a_81_4 = {41 63 53 76 63 73 74 2e 64 6c 6c } //1 AcSvcst.dll
		$a_81_5 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 20 4e 54 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 53 76 63 68 6f 73 74 5c 6e 65 74 73 76 63 73 } //1 SOFTWARE\Microsoft\Windows NT\CurrentVersion\Svchost\netsvcs
		$a_81_6 = {47 65 74 4b 65 79 62 6f 61 72 64 54 79 70 65 } //1 GetKeyboardType
		$a_81_7 = {46 69 6e 61 6c 32 2e 64 6c 6c } //1 Final2.dll
		$a_81_8 = {43 72 65 61 74 65 50 6f 74 50 6c 61 79 65 72 45 78 41 } //1 CreatePotPlayerExA
		$a_81_9 = {64 65 63 6f 64 65 } //1 decode
		$a_81_10 = {65 6e 63 6f 64 65 } //1 encode
		$a_81_11 = {43 72 65 61 74 65 50 6f 74 50 6c 61 79 65 72 45 78 57 } //1 CreatePotPlayerExW
		$a_81_12 = {44 65 73 74 72 6f 79 50 6f 74 50 6c 61 79 65 72 } //1 DestroyPotPlayer
		$a_81_13 = {4f 70 65 6e 50 6f 74 50 6c 61 79 65 72 55 72 6c 57 } //1 OpenPotPlayerUrlW
		$a_81_14 = {77 61 73 68 69 6e 6a 65 63 74 } //1 washinject
	condition:
		((#a_81_0  & 1)*2+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1+(#a_81_8  & 1)*1+(#a_81_9  & 1)*1+(#a_81_10  & 1)*1+(#a_81_11  & 1)*1+(#a_81_12  & 1)*1+(#a_81_13  & 1)*1+(#a_81_14  & 1)*1) >=16
 
}