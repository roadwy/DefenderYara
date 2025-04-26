
rule Spyware_Win32_Coolwebsearch_R{
	meta:
		description = "Spyware:Win32/Coolwebsearch.R,SIGNATURE_TYPE_PEHSTR,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {53 65 61 72 63 68 48 6f 6f 6b 2e 53 65 61 72 63 68 48 6f 6f 6b } //1 SearchHook.SearchHook
		$a_01_1 = {7b 46 44 39 42 43 30 30 34 2d 38 33 33 31 2d 34 34 35 37 2d 42 38 33 30 2d 34 37 35 39 46 46 37 30 34 43 32 32 7d 5c 55 52 4c 53 65 61 72 63 68 48 6f 6f 6b 73 } //1 {FD9BC004-8331-4457-B830-4759FF704C22}\URLSearchHooks
		$a_01_2 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 77 00 77 00 77 00 2e 00 73 00 65 00 61 00 72 00 63 00 68 00 2d 00 61 00 6e 00 64 00 2d 00 66 00 69 00 6e 00 64 00 2e 00 6e 00 65 00 74 00 } //1 http://www.search-and-find.net
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}