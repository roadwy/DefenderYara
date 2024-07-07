
rule Trojan_Win32_Reixecks_A{
	meta:
		description = "Trojan:Win32/Reixecks.A,SIGNATURE_TYPE_PEHSTR_EXT,05 00 04 00 04 00 00 "
		
	strings :
		$a_03_0 = {84 c0 0f 84 90 01 02 00 00 c7 45 90 01 01 72 65 6d 69 c7 45 90 01 01 78 73 69 64 c7 45 90 01 01 72 65 6d 69 c7 45 90 01 01 78 63 68 6b 90 00 } //2
		$a_01_1 = {6d 61 69 6c 2e 70 68 70 3f 61 63 74 3d 73 65 6e 74 26 74 6f 5f 69 64 3d } //1 mail.php?act=sent&to_id=
		$a_01_2 = {27 66 72 69 65 6e 64 73 27 3a 5b } //1 'friends':[
		$a_01_3 = {72 65 6d 69 78 63 68 6b 3d } //1 remixchk=
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}