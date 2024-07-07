
rule Trojan_Win32_Deepdo{
	meta:
		description = "Trojan:Win32/Deepdo,SIGNATURE_TYPE_PEHSTR_EXT,16 00 16 00 04 00 00 "
		
	strings :
		$a_00_0 = {61 00 75 00 74 00 6f 00 2e 00 73 00 65 00 61 00 72 00 63 00 68 00 2e 00 6d 00 73 00 6e 00 2e 00 63 00 6f 00 6d 00 2f 00 72 00 65 00 73 00 70 00 6f 00 6e 00 73 00 65 00 2e 00 61 00 73 00 70 00 } //10 auto.search.msn.com/response.asp
		$a_01_1 = {46 61 76 42 6c 6f 63 6b 2e 44 4c 4c 00 44 6c 6c 43 61 6e 55 6e 6c 6f 61 64 4e 6f 77 } //10 慆䉶潬正䐮䱌䐀汬慃啮汮慯乤睯
		$a_00_2 = {74 00 6e 00 3d 00 62 00 61 00 69 00 64 00 75 00 } //1 tn=baidu
		$a_00_3 = {74 00 6e 00 3d 00 64 00 65 00 65 00 70 00 62 00 61 00 72 00 } //1 tn=deepbar
	condition:
		((#a_00_0  & 1)*10+(#a_01_1  & 1)*10+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=22
 
}
rule Trojan_Win32_Deepdo_2{
	meta:
		description = "Trojan:Win32/Deepdo,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 04 00 00 "
		
	strings :
		$a_00_0 = {44 65 65 70 64 6f 55 70 64 61 74 65 } //1 DeepdoUpdate
		$a_00_1 = {44 65 65 70 64 6f 46 61 76 6f 72 69 74 65 55 70 64 61 74 65 } //1 DeepdoFavoriteUpdate
		$a_00_2 = {68 74 74 70 3a 2f 2f 74 6f 6f 6c 62 61 72 2e 64 65 65 70 64 6f 2e 63 6f 6d 2f 64 6f 77 6e 6c 6f 61 64 2f } //1 http://toolbar.deepdo.com/download/
		$a_02_3 = {6f 70 65 6e 00 00 00 00 72 65 67 73 76 72 33 32 2e 65 78 65 00 00 00 00 20 22 25 73 25 73 22 20 2f 73 00 00 72 65 67 25 64 00 00 00 25 73 25 73 00 00 00 00 25 73 5c 90 02 10 2e 74 6d 70 00 00 00 00 66 69 6c 65 25 64 00 00 75 72 6c 25 64 00 00 00 76 65 72 25 64 00 00 00 6d 61 69 6e 90 00 } //10
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_02_3  & 1)*10) >=11
 
}
rule Trojan_Win32_Deepdo_3{
	meta:
		description = "Trojan:Win32/Deepdo,SIGNATURE_TYPE_PEHSTR,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {75 73 72 69 6e 69 74 2e 44 4c 4c 00 44 6c 6c 43 61 6e 55 6e 6c 6f 61 64 4e 6f 77 } //1
		$a_01_1 = {2e 63 6e 2f 62 69 6e 2f 75 73 72 69 6e 69 74 2e 65 78 65 } //1 .cn/bin/usrinit.exe
		$a_01_2 = {74 6e 3d 64 65 65 70 62 61 72 5f } //1 tn=deepbar_
		$a_01_3 = {75 69 64 3d 25 73 26 75 72 6c 3d 25 73 26 } //1 uid=%s&url=%s&
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}