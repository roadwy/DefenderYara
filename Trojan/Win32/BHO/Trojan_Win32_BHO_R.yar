
rule Trojan_Win32_BHO_R{
	meta:
		description = "Trojan:Win32/BHO.R,SIGNATURE_TYPE_PEHSTR_EXT,ffffffd3 00 ffffffd3 00 06 00 00 "
		
	strings :
		$a_00_0 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 49 6e 74 65 72 6e 65 74 20 45 78 70 6c 6f 72 65 72 5c 4e 65 77 20 57 69 6e 64 6f 77 73 5c 41 6c 6c 6f 77 } //100 Software\Microsoft\Internet Explorer\New Windows\Allow
		$a_00_1 = {77 69 6e 64 6f 77 2e 6f 6e 65 72 72 6f 72 3d 66 75 6e 63 74 69 6f 6e 28 29 7b 72 65 74 75 72 6e 20 74 72 75 65 3b 7d } //100 window.onerror=function(){return true;}
		$a_02_2 = {68 74 74 70 3a 2f 2f 90 02 10 63 6c 69 63 6b 7a 63 6f 6d 70 69 6c 65 2e 63 6f 6d 2f 63 2f 25 6c 75 2f 25 6c 75 2f 25 6c 75 2f 25 6c 75 90 00 } //10
		$a_02_3 = {68 74 74 70 3a 2f 2f 90 02 10 75 61 74 6f 6f 6c 62 61 72 2e 63 6f 6d 2e 63 6f 6d 2f 63 2f 25 6c 75 2f 25 6c 75 2f 25 6c 75 2f 25 6c 75 90 00 } //10
		$a_00_4 = {65 78 65 2e 76 61 6b } //1 exe.vak
		$a_00_5 = {65 78 65 2e 73 67 73 6d 73 6d } //1 exe.sgsmsm
	condition:
		((#a_00_0  & 1)*100+(#a_00_1  & 1)*100+(#a_02_2  & 1)*10+(#a_02_3  & 1)*10+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1) >=211
 
}
rule Trojan_Win32_BHO_R_2{
	meta:
		description = "Trojan:Win32/BHO.R,SIGNATURE_TYPE_PEHSTR,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {69 65 78 70 6c 6f 72 65 2e 65 78 65 00 00 00 00 6f 70 65 6e } //1
		$a_01_1 = {00 63 6f 6d 6d 65 6e 74 32 00 } //1 挀浯敭瑮2
		$a_01_2 = {2e 44 4c 4c 00 44 6c 6c 43 61 6e 55 6e 6c 6f 61 64 4e 6f 77 } //1 䐮䱌䐀汬慃啮汮慯乤睯
		$a_01_3 = {00 53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 42 69 6e 64 00 } //1
		$a_01_4 = {00 2f 64 6f 77 6e 6c 6f 61 64 2e 70 68 70 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}