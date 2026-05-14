
rule Trojan_Win32_IrGramLoader_GVC_MTB{
	meta:
		description = "Trojan:Win32/IrGramLoader.GVC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_01_0 = {53 65 74 20 6f 53 68 65 6c 6c 20 3d 20 57 53 63 72 69 70 74 2e 43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 57 53 63 72 69 70 74 2e 53 68 65 6c 6c 22 29 } //1 Set oShell = WScript.CreateObject("WScript.Shell")
		$a_01_1 = {6f 53 68 65 6c 6c 2e 72 75 6e 20 22 70 6f 77 65 72 73 68 65 6c 6c 20 2d 65 78 65 63 20 62 79 70 61 73 73 20 2d 77 20 68 20 2d 6e 6f 50 20 2d 6e 6f 6e 49 20 2d 65 6e 63 } //1 oShell.run "powershell -exec bypass -w h -noP -nonI -enc
		$a_01_2 = {53 65 74 20 6f 53 68 65 6c 6c 20 3d 20 4e 6f 74 68 69 6e 67 } //1 Set oShell = Nothing
		$a_01_3 = {66 75 6e 63 74 69 6f 6e 20 43 68 65 63 6b } //1 function Check
		$a_01_4 = {73 6c 65 65 70 20 33 } //1 sleep 3
		$a_01_5 = {64 65 6c 20 2d 66 6f 72 63 65 20 2d 65 61 20 30 } //1 del -force -ea 0
		$a_01_6 = {7c 20 4f 75 74 2d 46 69 6c 65 20 2d 45 6e 63 6f 64 69 6e 67 20 61 73 63 69 69 20 2d 46 69 6c 65 50 61 74 68 } //1 | Out-File -Encoding ascii -FilePath
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=7
 
}