
rule TrojanProxy_Win32_Banker_AI{
	meta:
		description = "TrojanProxy:Win32/Banker.AI,SIGNATURE_TYPE_PEHSTR,ffffffe0 01 ffffffd6 01 0b 00 00 "
		
	strings :
		$a_01_0 = {65 6d 70 72 65 73 61 2e 70 61 63 } //100 empresa.pac
		$a_01_1 = {6b 61 72 61 76 65 6c 61 63 65 6e 74 65 72 40 68 6f 74 6d 61 69 6c 2e 63 6f 6d } //100 karavelacenter@hotmail.com
		$a_01_2 = {72 65 6d 65 74 65 6e 74 65 3d 46 54 50 40 68 6f 74 6d 61 69 6c 2e 63 6f 6d } //100 remetente=FTP@hotmail.com
		$a_01_3 = {71 75 65 72 6f 74 6f 70 73 79 73 2e 63 6f 6d 2f 73 6f 6c 75 63 61 6f 2f 65 6d 61 69 6c 2e 70 68 70 } //50 querotopsys.com/solucao/email.php
		$a_01_4 = {70 72 6c 75 69 7a 2e 70 72 6f 64 75 74 6f 72 61 61 6c 70 68 61 6e 65 74 2e 63 6f 6d 2e 62 72 2f 6c 61 6e 67 2f 65 6d 61 69 6c 2e 70 68 70 } //50 prluiz.produtoraalphanet.com.br/lang/email.php
		$a_01_5 = {6a 61 6f 6a 65 62 61 40 68 6f 74 6d 61 69 6c 2e 63 6f 6d } //30 jaojeba@hotmail.com
		$a_01_6 = {72 65 63 65 62 65 6e 64 6f 32 30 31 32 40 6c 69 76 65 2e 63 6f 6d } //30 recebendo2012@live.com
		$a_01_7 = {6d 73 6e 31 30 40 68 6f 74 6d 61 69 6c 2e 63 6f 6d 2e 62 72 } //20 msn10@hotmail.com.br
		$a_01_8 = {5c 69 66 74 2e 74 78 74 } //20 \ift.txt
		$a_01_9 = {65 6d 70 72 65 73 61 73 65 69 6b 65 62 61 74 69 73 74 61 2e 63 6f 6d 2f 69 6e 63 6c 75 64 65 73 2f } //100 empresaseikebatista.com/includes/
		$a_01_10 = {74 67 6b 6c 62 62 6e 6b 73 6c 6f 6f 70 2e 63 6f 6d 2f 69 6e 63 6c 75 64 65 73 2f } //100 tgklbbnksloop.com/includes/
	condition:
		((#a_01_0  & 1)*100+(#a_01_1  & 1)*100+(#a_01_2  & 1)*100+(#a_01_3  & 1)*50+(#a_01_4  & 1)*50+(#a_01_5  & 1)*30+(#a_01_6  & 1)*30+(#a_01_7  & 1)*20+(#a_01_8  & 1)*20+(#a_01_9  & 1)*100+(#a_01_10  & 1)*100) >=470
 
}