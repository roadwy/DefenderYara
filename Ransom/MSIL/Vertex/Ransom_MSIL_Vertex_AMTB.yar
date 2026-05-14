
rule Ransom_MSIL_Vertex_AMTB{
	meta:
		description = "Ransom:MSIL/Vertex!AMTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_80_0 = {56 65 72 74 65 78 4e 65 74 20 52 61 6e 73 6f 6d 77 61 72 65 20 53 74 61 72 74 65 64 } //VertexNet Ransomware Started  1
		$a_80_1 = {56 65 72 74 65 78 4e 65 74 53 74 61 67 65 32 } //VertexNetStage2  1
		$a_80_2 = {76 65 72 74 65 78 6e 65 74 2e 6c 6f 67 } //vertexnet.log  1
		$a_80_3 = {2e 76 65 72 74 65 78 } //.vertex  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1) >=4
 
}