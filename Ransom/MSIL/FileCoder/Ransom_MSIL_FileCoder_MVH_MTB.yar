
rule Ransom_MSIL_FileCoder_MVH_MTB{
	meta:
		description = "Ransom:MSIL/FileCoder.MVH!MTB,SIGNATURE_TYPE_PEHSTR,05 00 05 00 04 00 00 "
		
	strings :
		$a_01_0 = {50 53 39 39 41 75 74 6f 2d 44 69 61 6d 6f 6e 64 } //2 PS99Auto-Diamond
		$a_01_1 = {50 2e 6c 2e 65 2e 77 2e 74 2e 62 2e 71 2e 66 2e 5f } //1 P.l.e.w.t.b.q.f._
		$a_01_2 = {73 65 74 5f 55 73 65 53 68 65 6c 6c 45 78 65 63 75 74 65 } //2 set_UseShellExecute
		$a_01_3 = {47 65 74 45 78 74 65 6e 73 69 6f 6e } //1 GetExtension
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*2+(#a_01_3  & 1)*1) >=5
 
}