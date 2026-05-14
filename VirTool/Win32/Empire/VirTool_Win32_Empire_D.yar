
rule VirTool_Win32_Empire_D{
	meta:
		description = "VirTool:Win32/Empire.D,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 08 00 00 "
		
	strings :
		$a_80_0 = {2e 44 6f 77 6e 6c 6f 61 64 44 61 74 61 28 24 73 65 72 2b 24 74 29 3b } //.DownloadData($ser+$t);  1
		$a_80_1 = {3d 5b 53 79 73 74 65 6d 2e 54 65 78 74 2e 45 6e 63 6f 64 69 6e 67 5d 3a 3a 41 53 43 49 49 2e 47 65 74 42 79 74 65 73 28 27 } //=[System.Text.Encoding]::ASCII.GetBytes('  1
		$a_02_2 = {24 00 74 00 3d 00 27 00 2f 00 [0-30] 2e 00 70 00 68 00 70 00 } //1
		$a_02_3 = {24 74 3d 27 2f [0-30] 2e 70 68 70 } //1
		$a_80_4 = {2e 50 72 6f 78 79 3d 5b 53 79 73 74 65 6d 2e 4e 65 74 2e 57 65 62 52 65 71 75 65 73 74 5d 3a 3a 44 65 66 61 75 6c 74 57 65 62 50 72 6f 78 79 3b } //.Proxy=[System.Net.WebRequest]::DefaultWebProxy;  1
		$a_80_5 = {24 53 63 72 69 70 74 3a 50 72 6f 78 79 } //$Script:Proxy  1
		$a_80_6 = {2e 48 65 61 64 65 72 73 2e 41 64 64 28 27 55 73 65 72 2d 41 67 65 6e 74 27 2c 24 } //.Headers.Add('User-Agent',$  1
		$a_80_7 = {2e 48 65 61 64 65 72 73 2e 41 64 64 28 22 43 6f 6f 6b 69 65 22 2c 22 } //.Headers.Add("Cookie","  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_02_2  & 1)*1+(#a_02_3  & 1)*1+(#a_80_4  & 1)*1+(#a_80_5  & 1)*1+(#a_80_6  & 1)*1+(#a_80_7  & 1)*1) >=7
 
}