
rule Trojan_Win32_Fauppod_N{
	meta:
		description = "Trojan:Win32/Fauppod.N,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {78 77 6e 7a 72 73 77 6f 34 32 2e 64 6c 6c 00 52 6c 6f 73 72 65 65 6e 68 61 48 00 6b 65 72 6e 65 6c 33 32 2e 53 65 74 54 68 72 65 61 64 50 72 69 6f 72 69 74 79 42 6f 6f 73 74 } //1 睸穮獲潷㈴搮汬刀潬牳敥桮䡡欀牥敮㍬⸲敓呴牨慥偤楲牯瑩䉹潯瑳
	condition:
		((#a_01_0  & 1)*1) >=1
 
}