
rule Trojan_Win32_Startpage_LQ{
	meta:
		description = "Trojan:Win32/Startpage.LQ,SIGNATURE_TYPE_PEHSTR,03 00 03 00 05 00 00 "
		
	strings :
		$a_01_0 = {65 78 6e 2e 57 72 69 74 65 20 73 74 72 6c 6e 6b 20 26 20 22 5b 67 5d 22 20 26 20 74 6d 63 63 61 } //1 exn.Write strlnk & "[g]" & tmcca
		$a_01_1 = {66 73 6f 2e 63 6f 70 79 66 69 6c 65 20 77 73 68 2e 45 78 70 61 6e 64 45 6e 76 69 72 6f 6e 6d 65 6e 74 53 74 72 69 6e 67 73 28 22 25 57 49 4e 44 49 52 25 5c 73 79 73 74 65 6d 33 32 5c 22 29 26 22 77 73 63 72 69 70 74 2e 65 78 65 22 2c 70 61 74 68 6e 20 26 20 22 4e 74 79 70 65 2e 65 78 65 22 2c 74 72 75 65 } //1 fso.copyfile wsh.ExpandEnvironmentStrings("%WINDIR%\system32\")&"wscript.exe",pathn & "Ntype.exe",true
		$a_01_2 = {44 69 6d 20 66 73 6f 2c 77 73 68 2c 70 61 74 68 31 2c 70 61 74 68 32 2c 70 61 74 68 33 2c 70 61 74 68 34 2c 70 61 74 68 35 2c 70 78 74 68 31 2c 70 61 74 68 6e 2c 70 78 67 68 31 2c 63 6e 6d 2c 69 65 6e 61 6d 65 2c 69 65 6e 61 6d 65 78 2c 6f 6c 64 70 61 74 68 } //1 Dim fso,wsh,path1,path2,path3,path4,path5,pxth1,pathn,pxgh1,cnm,iename,ienamex,oldpath
		$a_01_3 = {69 65 6e 61 6d 65 3d 69 65 6e 61 6d 65 20 26 20 69 65 6e 61 6d 65 78 } //1 iename=iename & ienamex
		$a_01_4 = {69 65 6e 61 6d 65 3d 22 63 61 6f 2b 2b 74 69 61 6e 22 } //1 iename="cao++tian"
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=3
 
}