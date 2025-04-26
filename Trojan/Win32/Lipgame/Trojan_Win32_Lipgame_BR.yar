
rule Trojan_Win32_Lipgame_BR{
	meta:
		description = "Trojan:Win32/Lipgame.BR,SIGNATURE_TYPE_PEHSTR_EXT,07 00 06 00 0c 00 00 "
		
	strings :
		$a_01_0 = {63 6d 64 2e 65 78 65 20 2f 6b 20 65 63 68 6f 20 46 4f 25 73 52 25 73 4d 41 54 25 73 20 76 6f 6c 25 73 75 6d 65 20 25 73 } //1 cmd.exe /k echo FO%sR%sMAT%s vol%sume %s
		$a_01_1 = {25 73 5c 50 4f 25 73 4f 54 2e 6c 6e 6b } //1 %s\PO%sOT.lnk
		$a_01_2 = {2f 6b 20 65 63 68 6f 20 46 4f 52 4d 41 54 20 76 6f 6c 75 6d 65 20 5b 2f 46 53 3a 66 69 6c 65 2d 73 79 73 74 65 6d 5d 20 5b 2f 56 3a 6c 61 62 65 6c 5d 20 5b 2f 51 5d 20 5b 2f 41 3a 73 69 7a 65 5d 20 5b 2f 43 5d 20 5b 2f 58 5d } //1 /k echo FORMAT volume [/FS:file-system] [/V:label] [/Q] [/A:size] [/C] [/X]
		$a_01_3 = {68 74 74 70 3a 2f 2f 78 64 6c 2e 77 77 77 32 2e 69 6e 6b 6f 6e 74 2e 63 6f 6d 2f 6b 62 32 2e 70 68 70 3f 63 75 73 74 3d 25 64 26 77 3d 25 73 26 76 3d 25 73 26 6d 3d 25 64 26 65 3d 25 64 } //1 http://xdl.www2.inkont.com/kb2.php?cust=%d&w=%s&v=%s&m=%d&e=%d
		$a_01_4 = {25 73 5c 4d 69 63 72 6f 25 73 6e 74 69 53 70 25 73 } //1 %s\Micro%sntiSp%s
		$a_01_5 = {53 4f 46 54 57 41 52 25 73 49 43 52 4f 25 73 5c 57 49 4e 25 73 44 4f 57 53 5c 43 25 73 45 4e 54 25 73 53 49 4f 4e 5c 25 73 70 68 6f 6e 25 73 65 25 73 69 6e 67 73 5c } //1 SOFTWAR%sICRO%s\WIN%sDOWS\C%sENT%sSION\%sphon%se%sings\
		$a_01_6 = {25 73 5c 50 6f 70 75 70 25 73 } //1 %s\Popup%s
		$a_00_7 = {3d 48 3d 52 3d 61 3d 6b 3d 78 3d } //1 =H=R=a=k=x=
		$a_01_8 = {5c 69 6e 74 65 72 6e 74 2e 65 78 65 } //1 \internt.exe
		$a_01_9 = {25 73 5c 73 77 69 25 73 61 67 25 73 25 73 78 74 } //1 %s\swi%sag%s%sxt
		$a_01_10 = {25 73 5c 4b 25 73 25 73 32 32 25 73 2e 6c 6f 67 } //1 %s\K%s%s22%s.log
		$a_01_11 = {4c 69 70 25 73 47 61 6d 65 } //1 Lip%sGame
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_00_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1+(#a_01_10  & 1)*1+(#a_01_11  & 1)*1) >=6
 
}