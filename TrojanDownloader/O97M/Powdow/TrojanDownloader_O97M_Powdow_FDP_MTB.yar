
rule TrojanDownloader_O97M_Powdow_FDP_MTB{
	meta:
		description = "TrojanDownloader:O97M/Powdow.FDP!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {41 72 72 61 79 4c 69 73 74 62 6f 78 2e 4f 70 65 6e 20 22 47 45 54 22 2c 20 22 68 74 74 70 3a 2f 2f 22 20 26 20 4c 69 73 74 42 6f 78 31 2e 4c 69 73 74 28 33 29 2c 20 46 61 6c 73 65 } //1 ArrayListbox.Open "GET", "http://" & ListBox1.List(3), False
		$a_01_1 = {56 62 53 74 6f 72 61 67 65 2e 53 61 76 65 54 6f 46 69 6c 65 20 28 22 43 3a 5c 75 73 65 72 73 5c 70 75 62 6c 69 63 5c 66 64 70 63 2e 64 61 74 22 29 } //1 VbStorage.SaveToFile ("C:\users\public\fdpc.dat")
		$a_01_2 = {43 72 65 61 74 65 4f 62 6a 65 63 74 28 4c 69 73 74 42 6f 78 31 2e 4c 69 73 74 28 34 29 29 2e 52 75 6e 20 28 4f 70 74 69 6f 6e 53 77 61 70 44 61 74 61 62 61 73 65 20 2b 20 22 43 3a 5c 75 73 65 72 73 5c 70 75 62 6c 69 63 5c 66 64 70 63 2e 64 61 74 22 29 20 26 20 22 2c 44 6c 6c 55 6e 72 65 67 69 73 74 65 72 53 65 72 76 65 72 22 } //1 CreateObject(ListBox1.List(4)).Run (OptionSwapDatabase + "C:\users\public\fdpc.dat") & ",DllUnregisterServer"
		$a_01_3 = {4c 69 73 74 42 6f 78 31 2e 41 64 64 49 74 65 6d 20 28 22 72 75 6e 64 6c 6c 33 32 20 22 29 } //1 ListBox1.AddItem ("rundll32 ")
		$a_01_4 = {4c 69 73 74 42 6f 78 31 2e 41 64 64 49 74 65 6d 20 28 22 67 61 64 65 34 73 65 6e 61 74 65 2e 63 6f 6d 2f 6d 2e 64 6c 6c 22 29 } //1 ListBox1.AddItem ("gade4senate.com/m.dll")
		$a_01_5 = {4c 69 73 74 42 6f 78 31 2e 41 64 64 49 74 65 6d 20 28 22 57 53 63 72 69 70 74 2e 53 68 65 6c 6c 22 29 } //1 ListBox1.AddItem ("WScript.Shell")
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}