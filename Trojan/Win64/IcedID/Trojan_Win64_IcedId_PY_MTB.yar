
rule Trojan_Win64_IcedId_PY_MTB{
	meta:
		description = "Trojan:Win64/IcedId.PY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {ff ce 48 8d 15 ?? ?? ?? ?? 8a 0a 88 4c ?? ?? 80 44 [0-04] c0 64 [0-04] 8a 4c [0-02] 88 4c [0-02] 8a 4a 01 88 4c [0-02] 80 44 [0-04] 8a 4c [0-02] 08 4c [0-02] 8a 4c [0-02] 30 4c [0-02] fe 44 [0-02] 8a 4c [0-02] 88 0c 38 39 fe 74 [0-02] 48 ff c7 48 83 c2 [0-02] eb } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}