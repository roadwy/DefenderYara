
rule TrojanProxy_Win32_Virpen_A{
	meta:
		description = "TrojanProxy:Win32/Virpen.A,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {26 74 61 73 6b 3d } //1 &task=
		$a_01_1 = {13 41 64 64 50 6f 72 74 4e 75 6d 62 65 72 54 6f 48 6f 73 74 } //1 䄓摤潐瑲畎扭牥潔潈瑳
		$a_00_2 = {69 70 76 70 6e 6d 65 2e 72 75 2f 6c 6f 67 73 2f } //1 ipvpnme.ru/logs/
		$a_01_3 = {68 49 76 45 00 8d 45 fc } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_00_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}