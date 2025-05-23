
rule Trojan_Win32_Agent_APP{
	meta:
		description = "Trojan:Win32/Agent.APP,SIGNATURE_TYPE_PEHSTR_EXT,5a 00 50 00 09 00 00 "
		
	strings :
		$a_00_0 = {64 00 65 00 6b 00 33 00 39 00 30 00 66 00 30 00 66 00 39 00 32 00 38 00 64 00 39 00 32 00 } //10 dek390f0f928d92
		$a_01_1 = {33 39 39 64 39 39 32 6b 73 6a 66 68 73 39 } //10 399d992ksjfhs9
		$a_00_2 = {5c 6e 2e 69 6e 69 00 } //10
		$a_00_3 = {64 00 6f 00 63 00 75 00 6d 00 65 00 6e 00 74 00 2e 00 62 00 6f 00 64 00 79 00 2e 00 6f 00 6e 00 63 00 6f 00 6e 00 74 00 65 00 78 00 74 00 6d 00 65 00 6e 00 75 00 3d 00 6d 00 66 00 3c 00 2f 00 73 00 63 00 72 00 69 00 70 00 74 00 3e 00 } //10 document.body.oncontextmenu=mf</script>
		$a_00_4 = {66 00 75 00 6e 00 63 00 74 00 69 00 6f 00 6e 00 20 00 6d 00 66 00 28 00 29 00 20 00 7b 00 20 00 72 00 65 00 74 00 75 00 72 00 6e 00 20 00 66 00 61 00 6c 00 73 00 65 00 3b 00 20 00 7d 00 } //10 function mf() { return false; }
		$a_00_5 = {5c 77 62 65 6d 5c 63 73 72 73 73 2e 65 78 65 } //10 \wbem\csrss.exe
		$a_00_6 = {69 66 20 65 78 69 73 74 20 22 25 73 22 20 67 6f 74 6f 20 72 65 70 65 61 74 } //10 if exist "%s" goto repeat
		$a_00_7 = {69 6e 74 65 72 6e 65 74 20 73 65 74 74 69 6e 67 73 5c 7a 6f 6e 65 73 5c 33 } //10 internet settings\zones\3
		$a_01_8 = {64 61 74 61 3d 25 73 26 6b 65 79 3d 25 73 } //10 data=%s&key=%s
	condition:
		((#a_00_0  & 1)*10+(#a_01_1  & 1)*10+(#a_00_2  & 1)*10+(#a_00_3  & 1)*10+(#a_00_4  & 1)*10+(#a_00_5  & 1)*10+(#a_00_6  & 1)*10+(#a_00_7  & 1)*10+(#a_01_8  & 1)*10) >=80
 
}