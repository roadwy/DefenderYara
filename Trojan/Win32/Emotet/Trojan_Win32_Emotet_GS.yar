
rule Trojan_Win32_Emotet_GS{
	meta:
		description = "Trojan:Win32/Emotet.GS,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {6a 6a 72 6b 69 6f 70 6c 61 6b 64 65 72 74 79 62 66 67 74 72 74 79 75 69 6f 70 6c 6d 6b 61 73 } //1 jjrkioplakdertybfgtrtyuioplmkas
		$a_01_1 = {69 6e 61 61 61 72 6f 5f 65 73 73 5f 5f 6d 6f 72 79 } //1 inaaaro_ess__mory
		$a_01_2 = {68 69 72 74 75 75 6c 41 6c 6c 6f 63 } //1 hirtuulAlloc
		$a_01_3 = {68 68 68 6e 65 6c 33 32 2e 64 6c 6c } //1 hhhnel32.dll
		$a_01_4 = {68 78 61 71 66 74 6d 65 } //1 hxaqftme
		$a_01_5 = {75 76 70 68 6d 6d 64 73 68 79 76 } //1 uvphmmdshyv
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}