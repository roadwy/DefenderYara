
rule SoftwareBundler_Win32_MediaPass{
	meta:
		description = "SoftwareBundler:Win32/MediaPass,SIGNATURE_TYPE_PEHSTR_EXT,39 00 38 00 09 00 00 "
		
	strings :
		$a_01_0 = {53 6f 66 74 77 61 72 65 5c 41 70 70 44 61 74 61 4c 6f 77 5c 48 61 76 69 6e 67 46 75 6e 4f 6e 6c 69 6e 65 } //50 Software\AppDataLow\HavingFunOnline
		$a_01_1 = {2f 75 73 72 2f 67 65 74 67 65 6f 69 70 69 6e 66 6f 2e 70 68 70 3f 67 75 70 3d } //2 /usr/getgeoipinfo.php?gup=
		$a_01_2 = {2f 75 73 72 2f 72 65 67 69 73 74 65 72 5f 73 76 63 2e 70 68 70 3f 67 75 70 3d } //2 /usr/register_svc.php?gup=
		$a_01_3 = {7b 53 65 61 72 63 68 54 65 72 6d 73 7d } //1 {SearchTerms}
		$a_01_4 = {3c 6b 65 79 3e 48 6f 6d 65 50 61 67 65 3c 2f 6b 65 79 3e } //1 <key>HomePage</key>
		$a_01_5 = {64 6f 77 6e 6c 6f 61 64 2e 64 79 6d 61 6e 65 74 2e 63 6f 6d } //1 download.dymanet.com
		$a_01_6 = {62 69 67 6e 65 74 64 61 64 64 79 2e 63 6f 6d } //1 bignetdaddy.com
		$a_01_7 = {64 6f 77 6e 6c 6f 61 64 2e 74 72 75 65 61 64 73 2e } //1 download.trueads.
		$a_01_8 = {72 65 67 69 73 74 65 72 40 68 61 76 69 6e 67 66 75 6e 6f 6e 6c 69 6e 65 2e 63 6f 6d } //-100 register@havingfunonline.com
	condition:
		((#a_01_0  & 1)*50+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*-100) >=56
 
}