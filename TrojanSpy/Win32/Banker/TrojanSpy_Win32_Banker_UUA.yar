
rule TrojanSpy_Win32_Banker_UUA{
	meta:
		description = "TrojanSpy:Win32/Banker.UUA,SIGNATURE_TYPE_PEHSTR,0b 00 0b 00 08 00 00 "
		
	strings :
		$a_01_0 = {53 4f 46 54 57 41 52 45 5c 42 6f 72 6c 61 6e 64 5c 44 65 6c 70 68 69 5c 52 54 4c } //5 SOFTWARE\Borland\Delphi\RTL
		$a_01_1 = {6b 38 6b 38 38 2e 63 6f 6d 2f 78 69 61 6f 6a 69 6e } //2 k8k88.com/xiaojin
		$a_01_2 = {2f 61 63 63 74 2f 71 71 61 63 63 74 73 61 76 65 63 61 72 64 2e 63 67 69 3f 75 } //2 /acct/qqacctsavecard.cgi?u
		$a_01_3 = {43 6f 6e 6e 65 63 74 69 6f 6e 3a 20 43 6c 6f 73 65 } //1 Connection: Close
		$a_01_4 = {46 6f 6f 42 61 72 2e 6c 6f 63 61 6c 2e 68 6f 73 74 } //1 FooBar.local.host
		$a_01_5 = {26 50 61 73 73 77 6f 72 64 3d } //1 &Password=
		$a_01_6 = {26 50 43 4e 61 6d 65 3d } //1 &PCName=
		$a_01_7 = {48 54 54 50 2f 31 2e 31 } //1 HTTP/1.1
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1) >=11
 
}