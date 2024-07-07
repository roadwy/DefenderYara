
rule VirTool_Win32_Catchyikn_A{
	meta:
		description = "VirTool:Win32/Catchyikn.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {25 63 68 6f 69 63 65 25 22 3d 3d 22 31 22 20 67 6f 74 6f 20 54 43 50 0d 0a 69 66 20 2f 69 20 22 25 63 68 6f 69 63 65 25 22 3d 3d 22 32 22 20 67 6f 74 6f 20 53 59 4e 0d 0a 69 66 20 2f 69 20 22 } //1
		$a_01_1 = {65 6f 6c 3d 50 20 74 6f 6b 65 6e 73 3d 31 20 64 65 6c 69 6d 73 3d 20 22 20 25 25 69 20 69 6e 20 28 73 31 2e 74 78 74 29 } //1 eol=P tokens=1 delims= " %%i in (s1.txt)
		$a_01_2 = {5b 32 30 30 38 20 56 69 70 20 31 2e 30 5d } //1 [2008 Vip 1.0]
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}