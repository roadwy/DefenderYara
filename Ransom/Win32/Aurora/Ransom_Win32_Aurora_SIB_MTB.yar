
rule Ransom_Win32_Aurora_SIB_MTB{
	meta:
		description = "Ransom:Win32/Aurora.SIB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,34 00 2a 00 12 00 00 "
		
	strings :
		$a_80_0 = {3a 52 65 70 65 61 74 0d 0a 64 65 6c 20 22 25 73 22 0d 0a 69 66 20 65 78 69 73 74 20 22 25 73 22 20 67 6f 74 6f 20 52 65 70 65 61 74 0d 0a 72 6d 64 69 72 20 22 25 73 22 0d 0a 64 65 6c 20 22 25 73 22 } //:Repeat
del "%s"
if exist "%s" goto Repeat
rmdir "%s"
del "%s"  5
		$a_80_1 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 50 6f 6c 69 63 69 65 73 5c 53 79 73 74 65 6d } //SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System  5
		$a_80_2 = {5c 42 6f 6f 74 5c } //\Boot\  5
		$a_80_3 = {5c 42 4f 4f 54 53 45 43 54 } //\BOOTSECT  5
		$a_80_4 = {5c 70 61 67 65 66 69 6c 65 } //\pagefile  5
		$a_80_5 = {5c 53 79 73 74 65 6d 20 56 6f 6c 75 6d 65 20 49 6e 66 6f 72 6d 61 74 69 6f 6e 5c } //\System Volume Information\  5
		$a_80_6 = {62 6f 6f 74 6d 67 72 } //bootmgr  5
		$a_80_7 = {5c 52 65 63 6f 76 65 72 79 } //\Recovery  5
		$a_80_8 = {5c 4d 69 63 72 6f 73 6f 66 74 } //\Microsoft  5
		$a_80_9 = {45 76 65 72 79 20 62 79 74 65 20 6f 6e 20 61 6e 79 20 74 79 70 65 73 20 6f 66 20 79 6f 75 72 20 64 65 76 69 63 65 73 20 77 61 73 20 65 6e 63 72 79 70 74 65 64 } //Every byte on any types of your devices was encrypted  1
		$a_80_10 = {44 6f 6e 27 74 20 74 72 79 20 74 6f 20 75 73 65 20 62 61 63 6b 75 70 73 20 62 65 63 61 75 73 65 20 69 74 20 77 65 72 65 20 65 6e 63 72 79 70 74 65 64 20 74 6f 6f } //Don't try to use backups because it were encrypted too  1
		$a_80_11 = {54 6f 20 67 65 74 20 61 6c 6c 20 79 6f 75 72 20 64 61 74 61 20 62 61 63 6b 20 63 6f 6e 74 61 63 74 20 75 73 } //To get all your data back contact us  1
		$a_80_12 = {6f 6e 69 6f 6e 6d 61 69 6c 2e 6f 72 67 } //onionmail.org  1
		$a_80_13 = {70 72 6f 74 6f 6e 6d 61 69 6c 2e 63 6f 6d } //protonmail.com  1
		$a_80_14 = {64 6f 77 6e 6c 6f 61 64 65 64 20 66 69 6c 65 73 20 66 72 6f 6d 20 79 6f 75 72 20 73 65 72 76 65 72 73 } //downloaded files from your servers  1
		$a_80_15 = {77 69 6c 6c 20 73 65 6c 6c 20 74 68 65 6d 20 6f 6e 20 74 68 65 20 64 61 72 6b 6e 65 74 } //will sell them on the darknet  1
		$a_80_16 = {70 79 73 61 } //pysa  1
		$a_80_17 = {2e 6f 6e 69 6f 6e 2f } //.onion/  1
	condition:
		((#a_80_0  & 1)*5+(#a_80_1  & 1)*5+(#a_80_2  & 1)*5+(#a_80_3  & 1)*5+(#a_80_4  & 1)*5+(#a_80_5  & 1)*5+(#a_80_6  & 1)*5+(#a_80_7  & 1)*5+(#a_80_8  & 1)*5+(#a_80_9  & 1)*1+(#a_80_10  & 1)*1+(#a_80_11  & 1)*1+(#a_80_12  & 1)*1+(#a_80_13  & 1)*1+(#a_80_14  & 1)*1+(#a_80_15  & 1)*1+(#a_80_16  & 1)*1+(#a_80_17  & 1)*1) >=42
 
}