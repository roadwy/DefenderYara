
rule Trojan_Win32_Gedanjo_A{
	meta:
		description = "Trojan:Win32/Gedanjo.A,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {2f 53 74 61 72 74 2e 68 74 6d 3f 41 72 65 61 49 44 3d } //1 /Start.htm?AreaID=
		$a_01_1 = {38 38 30 30 2e 6f 72 67 } //1 8800.org
		$a_01_2 = {4c 61 73 74 53 74 61 72 74 54 69 6d 65 5f 25 64 } //1 LastStartTime_%d
		$a_01_3 = {2e 63 6e 2f 45 78 65 49 6e 69 31 34 2f 4d 65 73 73 65 6e 67 65 72 2e 74 78 74 } //1 .cn/ExeIni14/Messenger.txt
		$a_01_4 = {66 61 63 65 70 69 7a 7a 61 2e 63 6e } //1 facepizza.cn
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}