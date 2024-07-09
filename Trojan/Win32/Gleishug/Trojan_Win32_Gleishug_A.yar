
rule Trojan_Win32_Gleishug_A{
	meta:
		description = "Trojan:Win32/Gleishug.A,SIGNATURE_TYPE_PEHSTR_EXT,07 00 05 00 05 00 00 "
		
	strings :
		$a_03_0 = {2e 63 6f 6d 2f 3f 73 69 64 3d [0-12] 26 73 3d 7b 73 65 61 72 63 68 54 65 72 6d 73 7d } //3
		$a_03_1 = {2e 6e 65 74 2f 3f 73 69 64 3d [0-12] 26 73 3d 7b 73 65 61 72 63 68 54 65 72 6d 73 7d } //3
		$a_01_2 = {5c 73 65 61 72 63 68 2e 73 71 6c 69 74 65 22 20 22 55 50 44 41 54 45 20 65 6e 67 69 6e 65 5f 64 61 74 61 20 53 45 54 20 6e 61 6d 65 20 3d 20 27 6f 72 64 65 72 27 20 57 48 45 52 45 20 65 6e 67 69 6e 65 69 64 20 4c 49 4b 45 20 27 25 67 6f 6f 67 6c 65 25 27 22 } //2 \search.sqlite" "UPDATE engine_data SET name = 'order' WHERE engineid LIKE '%google%'"
		$a_01_3 = {5c 53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 49 6e 74 65 72 6e 65 74 20 45 78 70 6c 6f 72 65 72 5c 53 65 61 72 63 68 53 63 6f 70 65 73 } //2 \Software\Microsoft\Internet Explorer\SearchScopes
		$a_01_4 = {5c 4d 6f 7a 69 6c 6c 61 20 46 69 72 65 66 6f 78 5c 73 65 61 72 63 68 70 6c 75 67 69 6e 73 5c 67 6f 6f 67 6c 65 2a 2e 78 6d 6c } //2 \Mozilla Firefox\searchplugins\google*.xml
	condition:
		((#a_03_0  & 1)*3+(#a_03_1  & 1)*3+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2+(#a_01_4  & 1)*2) >=5
 
}