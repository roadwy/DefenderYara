
rule Trojan_Win32_Startpage_XA{
	meta:
		description = "Trojan:Win32/Startpage.XA,SIGNATURE_TYPE_PEHSTR_EXT,08 00 07 00 08 00 00 "
		
	strings :
		$a_01_0 = {5c 49 6e 74 65 72 6e 65 74 20 45 78 70 6c 6f 72 65 72 2e 6d 73 6d 34 } //1 \Internet Explorer.msm4
		$a_01_1 = {4c 6f 76 65 33 36 30 3d 34 2a 39 30 2b 52 2b 69 6e 67 2a 33 36 30 } //1 Love360=4*90+R+ing*360
		$a_01_2 = {2e 39 37 37 64 68 2e 63 6f 6d } //1 .977dh.com
		$a_01_3 = {53 4f 46 54 57 41 52 45 5c 43 6c 61 73 73 65 73 5c 6d 73 6e 34 66 69 6c 65 5c 44 65 66 61 75 6c 74 49 63 6f 6e } //1 SOFTWARE\Classes\msn4file\DefaultIcon
		$a_01_4 = {7b 46 34 36 45 35 31 32 42 2d 45 32 41 43 2d 34 39 30 31 2d 39 37 43 32 2d 33 41 33 35 39 31 30 43 30 32 35 36 7d } //1 {F46E512B-E2AC-4901-97C2-3A35910C0256}
		$a_01_5 = {5c 43 6f 6d 44 6c 6c 73 5c 31 31 34 33 5c 62 75 62 68 6c 71 2e 65 78 65 22 20 22 25 31 22 } //1 \ComDlls\1143\bubhlq.exe" "%1"
		$a_01_6 = {2e 39 32 6e 69 6d 6d 2e 63 6f 6d 2f 3f } //1 .92nimm.com/?
		$a_01_7 = {5c c6 af c1 c1 c3 c0 c3 bc cd bc 2e 75 72 6c 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1) >=7
 
}